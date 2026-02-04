import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes

import utmn_opencti_module.UTMNOpenCTIConfig as interface_conf
from utmn_opencti_module.opencti_handler import OpenCTIHandler


class UTMN_OpenCTIInterface(IrisModuleInterface):

    name = "UTMN_OpenCTIInterface"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):

        self.module_id = module_id
        module_conf = self.module_dict_conf

        run_async = bool(module_conf.get('opencti_run_async_hooks'))

        if module_conf.get('opencti_on_alert_create_enabled', False):
            status = self.register_to_hook(module_id, iris_hook_name='on_postload_alert_create',
                                           run_asynchronously=run_async)
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())
            else:
                self.log.info('Successfully registered on_postload_alert_create hook')
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_alert_create')

        if module_conf.get('opencti_on_alert_update_enabled', True):
            status = self.register_to_hook(module_id, iris_hook_name='on_postload_alert_update',
                                           run_asynchronously=run_async)
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())
            else:
                self.log.info('Successfully registered on_postload_alert_update hook')
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_alert_update')

        if module_conf.get('opencti_manual_hook_enabled', True):
            status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_alert',
                                           manual_hook_name='OpenCTI enrichment',
                                           run_asynchronously=run_async)
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())
            else:
                self.log.info('Successfully registered on_manual_trigger_alert hook')
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_manual_trigger_alert')


        if module_conf.get('opencti_manual_ioc_hook_enabled', True):
            status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_ioc',
                                           manual_hook_name='OpenCTI enrichment',
                                           run_asynchronously=run_async)
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())
            else:
                self.log.info('Successfully registered on_manual_trigger_ioc hook')
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_manual_trigger_ioc')

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):

        self.log.info(f'Received {hook_name}')
        if hook_name in ['on_postload_alert_create', 'on_postload_alert_update', 'on_manual_trigger_alert']:
            status = self._handle_alert(data=data)
        elif hook_name in ['on_manual_trigger_ioc']:
            status = self._handle_ioc(data=data)
        else:
            self.log.critical(f'Received unsupported hook {hook_name}')
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        if status.is_failure():
            self.log.error(f'Encountered error processing hook {hook_name}')
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        self.log.info(f'Successfully processed hook {hook_name}')
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))

    def _handle_alert(self, data) -> InterfaceStatus.IIStatus:

        try:
            module_conf = self.module_dict_conf
        except Exception as exc:
            self.log.error(f'Failed to load module configuration: {exc}')
            module_conf = {}

        if not isinstance(module_conf, dict):
            self.log.error('Module configuration malformed, using empty config')
            module_conf = {}

        try:
            server_conf = self.server_dict_conf
        except Exception as exc:
            self.log.error(f'Failed to load server configuration: {exc}')
            server_conf = {}

        if not isinstance(server_conf, dict):
            self.log.error('Server configuration malformed, using empty config')
            server_conf = {}

        opencti_handler = OpenCTIHandler(
            mod_config=module_conf,
            server_config=server_conf,
            logger=self.log
        )

        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

        for element in data:
            status = opencti_handler.enrich_alert(alert=element)
            in_status = InterfaceStatus.merge_status(in_status, status)

        return in_status(data=data)

    def _handle_ioc(self, data) -> InterfaceStatus.IIStatus:

        try:
            module_conf = self.module_dict_conf
        except Exception as exc:
            self.log.error(f'Failed to load module configuration: {exc}')
            module_conf = {}

        if not isinstance(module_conf, dict):
            self.log.error('Module configuration malformed, using empty config')
            module_conf = {}

        try:
            server_conf = self.server_dict_conf
        except Exception as exc:
            self.log.error(f'Failed to load server configuration: {exc}')
            server_conf = {}


        if not isinstance(server_conf, dict):
            self.log.error('Server configuration malformed, using empty config')
            server_conf = {}

        opencti_handler = OpenCTIHandler(
            mod_config=module_conf,
            server_config=server_conf,
            logger=self.log
        )

        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

        for element in data:
            status = opencti_handler.enrich_ioc(element)
            in_status = InterfaceStatus.merge_status(in_status, status)

        return in_status(data=data)
