
rule n3ed_539b07a9c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.539b07a9c2000b32"
     cluster="n3ed.539b07a9c2000b32"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['01240863c545ebb422403ca707537ce7','0c9399b08ea0306d778ca83ebe06f028','ee4d0a2df449c9a10205e547d178031c']"

   strings:
      $hex_string = { 45fc8b462885c0897df80f843504000050ff15b01032598d4f013b4e6073298b7d1c8d14c98d14978b7d28393a7506837adc02740b4183c2243b4e6072eaeb08 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
