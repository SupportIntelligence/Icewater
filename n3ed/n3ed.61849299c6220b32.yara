
rule n3ed_61849299c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61849299c6220b32"
     cluster="n3ed.61849299c6220b32"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['066584d2b29fd5562f22ceb78a2c6176','08401f7bd793c2f127a8dea136fc5dd3','bcb87702927986922a3f7ee09ef6b29a']"

   strings:
      $hex_string = { 3acb74060fbec947eb036a30598808404a3bd37fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e832 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
