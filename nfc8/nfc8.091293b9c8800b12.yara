
rule nfc8_091293b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.091293b9c8800b12"
     cluster="nfc8.091293b9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos banker androidos"
     md5_hashes="['0ea44063a3dee4a90cdae6a6b8d282cc3d1299fe','86a890f2bf1bd3bbfef611d494e16dd4168d2084','c7068e2a9204c4933fe5d0c5775331b3c27d9ff0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.091293b9c8800b12"

   strings:
      $hex_string = { eba731866b09aed5a32830e5256fc1c4bb3874d01b339f7bf945a592f11ab7fb8932f71cbfa2ad14d79d136783d8c5c612c87107e666654c16f49922f3cd8a87 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
