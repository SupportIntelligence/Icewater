
rule m3e9_6b6f231d44e66916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f231d44e66916"
     cluster="m3e9.6b6f231d44e66916"
     cluster_size="481"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['0022b16bb2c1ab8694af4285de53e859','013b69f078b75d6293b21cab076d13d2','182909eb729a5ece66503d1a7510cfcd']"

   strings:
      $hex_string = { 73451991a13bdc663521732aca34607c6a829a2e7e3ea4603c7d7b2e1ddd43607e72ac2962159292f687ff96de67deb857cd57ed6104ff05185169b16e1d2d4c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
