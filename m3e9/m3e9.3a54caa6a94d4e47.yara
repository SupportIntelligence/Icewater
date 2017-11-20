
rule m3e9_3a54caa6a94d4e47
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a54caa6a94d4e47"
     cluster="m3e9.3a54caa6a94d4e47"
     cluster_size="92"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0722a3b96c74ab0dea21c1fd2d055409','54fb5c807a7ce83d32275fb91d4ba450','a9b57cb72c9a232548b92155c6fef80f']"

   strings:
      $hex_string = { 413f62a976f5c044ba16d08159ace974876e9eaa82268667a62210e3d6b6fa706409f436bca58dc15f9a600193db143d13790ed1ee0425fe6af7f0293173c320 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
