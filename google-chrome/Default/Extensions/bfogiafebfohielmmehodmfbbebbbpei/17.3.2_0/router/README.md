# Router Instruction
## Steps to add a new route path
(1) Let say you'd like to add a new path `/extTabPages/settings`. Create a file `settings.tsx` in the folder `/custom/router/routes/extTabPages`
([An official doc page](https://tanstack.com/router/v1/docs/framework/react/guide/file-based-routing) to know more about in defining path in other various ways).

Define the route in the `settings.tsx` file. Here, you normally define the path name, search params types, and other hooks to be called at certain life cycle, for example `beforeLoad`.
```typescript
// /custom/router/routes/extTabPages/settings.tsx
import {createFileRoute, redirect} from '@tanstack/react-router'
import {z} from 'zod'

const settingsSchema = z.object({
   userId: z.number(),
})

export const Route = createFileRoute('/extTabPages/settings')({
   validateSearch: settingsSchema,
})
```

(3) Run the npm command `npm run generate-route-types` command. This will output a new file `routeTree.gen.ts` under the `/custom/router`, which contains the router tree.

(4) Register the view component to the router in the `routerIdComponentMap`. 
Each UI surface will have its own `routerIdComponentMap`.
For the Ext Tab Page UI, you can find it [here](../extension_pages/react/extension_page_app/routerIdComponentMap.tsx). The others don't have it at the moment.

```tsx
import {Settings} from 'path-to-settings'

export const routerIdComponentMap = new Map()
routerIdComponentMap.set('/extTabPages/settings', Settings)
```

(5) Call the `updateRouter` with the updated `routerIdComponentMap` before the main app is rendered.
```tsx
/*...*/

const main = () => {
  updateRouter({routerMapIdComponent})
  /*...*/
  const rootDom = document.getElementById('root')
  const root = createRoot(rootDom)
  root.render(<App/>)
}
```

## How to navigate to different views?
Mainly three possible ways: (1) `navigate()`, (2) `<Navigate/>`, or `<Link/>`.

### `navigate()`
In your view component, you can access the `route` object by calling the function `getRouteApi()` with the `pathId`.
Then, by calling the `route.useNavigate()`, you can access the `navigate()` function.

```tsx
import {getRouteApi} from "@tanstack/react-router"

const route = getRouteApi('/extTabPages/settings')

const SettingsViewComponent = () => {
   const navigate = router.useNavigate()
   useEffect(() => {
     navigate({to: '/extTabPages/addNewRecord'})
   }, [/*...*/])
   /*...*/
}
```

### `<Navigate/>`

The `<Navigate/>` component is useful when you want to redirect users to certain views without user action, for example redirecting users to default page when they access undefined paths.

```tsx
import {getRouteApi} from "@tanstack/react-router"

const route = getRouteApi('/extTabPages/profile')

const ProfilePage = () => {
  const {userId} = route.useSearch()
  /*...*/
  return (
    !!userId ? <Profile/> : <Navigate to="/extTabPages/LoginRequired"/>
  )
}
```

### `<Link/>`
The `<Link/>` component is useful when the redirection requires users' interaction such as clicks.
By clicking the `<Link/>` component, the users will be redirected to the path provided to the component.

```tsx
import {getRouteApi, Link} from "@tanstack/react-router"

const ProfilePage = () => {
  /*...*/
  return (
    <div id="profile-page">
      {/*...*/}
      <Link to="/extTabPages/settings">Settings</Link>
      {/*...*/}
    </div>
  )
}
```


## Future Plans
1. The router is implemented in both Form Filler and Ext Tab (as of 3/12/2025). Implement it in Toolbar Window as well

## References
1. [Tanstack Router](https://tanstack.com/router/v1/docs/framework/react/start/overview)
2. [Why Memory History in Form Filler](https://docs.google.com/document/d/1vuummxCISRqiWJBzQ0te9StQY0lzPPJdVaBqgdWZ89M/edit?usp=sharing)