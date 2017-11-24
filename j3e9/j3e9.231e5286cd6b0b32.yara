
rule j3e9_231e5286cd6b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.231e5286cd6b0b32"
     cluster="j3e9.231e5286cd6b0b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['8fe083be037ec776a6385f094937d4df','9d6f91313f756ac4f1e9c432f20d7ed0','f912ae71b01b83171b7f4af9db2dd49d']"

   strings:
      $hex_string = { 2c6a580311f72390ccfc495fb5af951a3ed0c72bca6b5f33d7ed842567511efe5c050d173abeae4bd9e9a49e20f550561261c94378c9c237d664997a8863799d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
