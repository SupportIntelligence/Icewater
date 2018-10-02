
rule k26c3_2bb4d534cc22f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c3.2bb4d534cc22f112"
     cluster="k26c3.2bb4d534cc22f112"
     cluster_size="109"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mirai linux backdoor"
     md5_hashes="['ea91d757aa4429b24df25622a7a3ec7006843de5','dbe21479e3fc17b74cf530e8a729e08214ab985e','f50b0665b145514aca449b7b50049a990df88bd6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c3.2bb4d534cc22f112"

   strings:
      $hex_string = { feb44091fe9c4bfffe9c83aa001048003f99812100085694203e7e8011205694e03e1d2900187d29ca14880900147c6304307fbd1a1493bc0010409efeb03ba0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
