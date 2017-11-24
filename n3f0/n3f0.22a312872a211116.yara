
rule n3f0_22a312872a211116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.22a312872a211116"
     cluster="n3f0.22a312872a211116"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira ccpk icgh"
     md5_hashes="['a0c7b29144e807b3874d1efe57cde97a','a1de144868547b7e288429b38478310d','d5f3ef48428f91f48e28c4b96c7671e9']"

   strings:
      $hex_string = { 3dc55d3b8b9e925a0d65170c7581867576c9484d65ccc6910ea6aea019e3a346bcdd8ddef99dfbeb7eaa51436fc6df8ce980c947ba93a841bf3cd5a6cfff491f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
