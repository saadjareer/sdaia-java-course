package org.example.helpers;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.example.dto.ErrorMessage;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.StringTokenizer;

@Provider
public class AuthFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!requestContext.getUriInfo().getPath().contains("secures")) return;

        List<String> authHeaders = requestContext.getHeaders().get("Authorization");
        if (authHeaders != null && !authHeaders.isEmpty()) {
            String authHeader = authHeaders.get(0);
            authHeader = authHeader.replace("Basic ", "");
            authHeader = new String(Base64.getDecoder().decode(authHeader));
            StringTokenizer tokenizer = new StringTokenizer(authHeader, ":");
            String username = tokenizer.nextToken();
            String password = tokenizer.nextToken();

            if (!isUserAllowed(username, password)) {
                ErrorMessage err = new ErrorMessage();
                err.setErrorContent("LOGIN-ERROR: Invalid username or password");
                err.setErrorCode(Response.Status.UNAUTHORIZED.getStatusCode());
                Response res = Response.status(Response.Status.UNAUTHORIZED)
                        .entity(err)
                        .build();

                requestContext.abortWith(res);
            }
        }
    }

    private boolean isUserAllowed(final String username, final String password) {
        boolean isUserAllowed = false;

        // Access the database and do this part yourself
        // Step 1: Search the username in list of all users in your DB
        // Step 2: If user exists, Get the user's password from database returned record and match with password in input parameter
        // Step 3: If both passwords match [DB vs INPUT] then continue
        // Step 4: Else return isUserAllowed [false]

        if (username.equals("admin") && password.equals("admin")) {
            isUserAllowed = true;
        }
        return isUserAllowed;
    }
}
