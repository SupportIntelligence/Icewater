
rule j3e9_231e5286cc9b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.231e5286cc9b0b32"
     cluster="j3e9.231e5286cc9b0b32"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['46a32dd6b2ecaf6093d257bcee51bdfc','4c8bf78f17c147bba27ed14a9e0d19f3','e286e64c10b88c321fc6cd5b8798fad8']"

   strings:
      $hex_string = { 2c6a580311f72390ccfc495fb5af951a3ed0c72bca6b5f33d7ed842567511efe5c050d173abeae4bd9e9a49e20f550561261c94378c9c237d664997a8863799d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
