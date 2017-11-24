
rule m2321_4b173294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b173294d6830912"
     cluster="m2321.4b173294d6830912"
     cluster_size="23"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['0f05a64d999218a776a90b87755a655e','12d07b7ffe04ed62a4eb49cfae8a6fd2','b2950f6664ad3d0dd0a6566094619367']"

   strings:
      $hex_string = { f5ac83ea580745d5b82780772015af87c8105b080c69f24017cf5e8998b59c3c006435289b41bc1eaf5304c90f66d3a665a106fee7e3aa2b3fdf8597ef42f1dd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
