// Small interactivity for the home page
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('a[href="#features"]').forEach(function(el){
    el.addEventListener('click', function(e){
      e.preventDefault();
      document.getElementById('features').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
});
