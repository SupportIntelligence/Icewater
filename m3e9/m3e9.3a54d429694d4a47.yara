
rule m3e9_3a54d429694d4a47
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a54d429694d4a47"
     cluster="m3e9.3a54d429694d4a47"
     cluster_size="1185"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['00680b7bd8675607de9376c0e8eee13c','006ad91ca46b8684317ecbdd9228e5ac','04fb16c309fd347dff0fbf4daffe78c1']"

   strings:
      $hex_string = { aa34f6c15f163de1660c760119ad6d02a3b6efec054dcba1b0bece8638dd6147c006cce962593faefef42618dfd660e05595f9246ac674d790d154ac9ac56ca0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
