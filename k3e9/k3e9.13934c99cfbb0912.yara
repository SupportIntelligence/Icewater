
rule k3e9_13934c99cfbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13934c99cfbb0912"
     cluster="k3e9.13934c99cfbb0912"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androm backdoor symmi"
     md5_hashes="['2253b6edd276785887b9180e6a8c9185','29fbd05f3f650e79a48e445aed5df3d0','c5cd1835297fd924f888599012c96013']"

   strings:
      $hex_string = { 4e60bb5bdfad7aa83c46c8feb28426be10a71cb4e31d3ae075bdcab00620ef9ddce318fab1fde90ad81f5da1dd14369f7338b5f9296267b90f965c3e492eda78 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
