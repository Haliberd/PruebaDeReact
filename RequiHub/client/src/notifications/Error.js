import React, {Component} from 'react';

class Error extends Component {
  render(){
    return(
      <div className='container'>
        <div className='jumbotron mt-5'>
          <div className='col-sm-8 mx-auto'>
            <h1 className='text-center'> Error al iniciar sesión </h1>
          </div>
        </div>
      </div>
    )
  }
}

export default Error;
