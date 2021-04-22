import asyncio
import helpers.ssh_authkeys_manager

cleaning_lady_unchained = True
cleaning_lady_sleepsecs = 20


async def jobs():
    # all the tasks that need to be done:
    helpers.ssh_authkeys_manager.remove_expired_ssh_auth_keys()


async def brooming():
    while cleaning_lady_unchained:
        await jobs()
        print("Cleaning Lady has started")
        await asyncio.sleep(cleaning_lady_sleepsecs)

async def start(sleepsecs: int = 60):
    global cleaning_lady_unchained
    global cleaning_lady_sleepsecs
    cleaning_lady_unchained = True
    cleaning_lady_sleepsecs = sleepsecs
    print("starting OpenSupportTool Cleaning lady...")
    asyncio.create_task(brooming())

def stop():
    global cleaning_lady_unchained
    cleaning_lady_unchained = False
