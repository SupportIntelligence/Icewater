
rule k3ec_09e7613d80800132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.09e7613d80800132"
     cluster="k3ec.09e7613d80800132"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir nimda runouce"
     md5_hashes="['350ff7e037ac78e9e88daf8dac6b36ed','830bcacfb49338756c109c74abafc20d','c2c06cd764ebd92496d4c1232ad8f3fb']"

   strings:
      $hex_string = { 58663d60e80f8486000000814b24000000e06a026a00ff7508ff563c83f8ff74705005fc1900002b43148943108b53083bc272168943088b4f384903c103d1f7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
