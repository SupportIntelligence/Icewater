
rule m2377_58993949c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.58993949c4000932"
     cluster="m2377.58993949c4000932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['021ca1ae485b6c7ea13c814f4b649da7','032a759aa52cf93c16f0c24d3f9574f4','a801163e91dc727fcaa20f5b24a11737']"

   strings:
      $hex_string = { 035d4a04054e83490190e9e38206e515a519c6be11209acf690e615a3f7b3c803d666bfcd9463b71ae438dbccbcd23288176bd7a87c7cae1007799d14f40579c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
