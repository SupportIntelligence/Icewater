
rule n3e9_093185bad9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.093185bad9e30912"
     cluster="n3e9.093185bad9e30912"
     cluster_size="34"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['02f15c282911db4f442c359227ca6d1f','098076b2728e3be1224f0f77070c6f15','87e6f02d922aa13a167c07fbc21b635b']"

   strings:
      $hex_string = { 80e5cf023f6564e645612d9414c899da46c15fce1fa350d937c3f49bd5a4f7cd1beb745a4ee254566f8d6b55beff061ae7a7fc9eae6a5c21a226d3537ad89c41 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
