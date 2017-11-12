
rule m3ec_393ebd49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.393ebd49c0000912"
     cluster="m3ec.393ebd49c0000912"
     cluster_size="32142"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector squdf"
     md5_hashes="['0000a123deee7f35941b3fc8e36c13d0','0001da0c65062f44c7d076141f4a9116','001fd1bad7dce995d53e6750ea64c56f']"

   strings:
      $hex_string = { 71e9ffff595f5e5b8be55dc39083c4bc54e8cb1c0000f644242c0174070fb7442430eb05b80a00000083c444c3e81b1d0000c39090558bec8b450850e8121d00 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
