
rule m3e9_3a4912d98dbb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a4912d98dbb0b16"
     cluster="m3e9.3a4912d98dbb0b16"
     cluster_size="27"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex malicious"
     md5_hashes="['2cea4b2392ff2ccb3964b4c8d1a1b6ae','7e8ffa87e9d5167e0e439b257da3ad0e','c96c48aed7489ebcfa64c5eca72b2a18']"

   strings:
      $hex_string = { 69071d150a3c3b3b2c273d1f2c3b3a20262700090077270518130214033e1300290089dac6cfdddec8dbccd5c4e0eafbe6fae6effdd5dee0e7ede6fefad5cafc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
