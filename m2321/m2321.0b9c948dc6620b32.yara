
rule m2321_0b9c948dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9c948dc6620b32"
     cluster="m2321.0b9c948dc6620b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis hafen mikey"
     md5_hashes="['4b6e1fcb1056b34ff7495e9f886a3473','761b1f185844da63821b04031ab1f1fe','ff17cd596dfe0edf57bcb672b23ea7d0']"

   strings:
      $hex_string = { 7a11a046f379f2a6578db964323cddc57b4af017512b658c6abe88df547cbf6b90fb4e93bb74e5c3b05e687f8bcee0accfff23f4ef890b12f969e31ee829365f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
