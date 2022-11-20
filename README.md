# IKE


  # Генератор::
   
    python gen.py -p 4562191 --hash md5
    
   На выходе получим файл с имененм 4562191_md5.txt
    Формат данных в файле::
   
            Ni*Nr*g_x*g_y*Ci*Cr*SAi*IDi*HASH
   
  # Восстановление пароля::
    
    python crack.py -m dddddddd -f check.txt
    
    
  В случае успешно найденного пароля выводится сообщение:
    
     Password recovered! 
     Password  :: *значение найденного пароля в кодировке ascii*
  
  Иначе выводится сообщение:
   
      Password was not found
   
