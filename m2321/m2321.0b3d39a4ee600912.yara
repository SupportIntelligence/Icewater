
rule m2321_0b3d39a4ee600912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3d39a4ee600912"
     cluster="m2321.0b3d39a4ee600912"
     cluster_size="36"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['023a48e566f834530d2c05f4be4190dd','033da0a9b6ef350c87ecd6dc311c1e44','7e763ee9c6e8780fb1d78e4a13360b1d']"

   strings:
      $hex_string = { 42a19932a40459e97982fada0f4dcadb3039410b5d07c4573402a8a7a3b8316b769c7a9bdcb438ba83eb3c05b3623aec1e1f80d14369bfe1ce893ed2ae97c58b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
