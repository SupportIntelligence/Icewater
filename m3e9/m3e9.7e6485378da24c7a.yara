
rule m3e9_7e6485378da24c7a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7e6485378da24c7a"
     cluster="m3e9.7e6485378da24c7a"
     cluster_size="93"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus backdoor wbna"
     md5_hashes="['00d7eb8c56b66a9502e1b5ac2feb5592','03f4e13562e69342b4bde1027593bdf7','79cc79410477e6486e3af0aa70be69b1']"

   strings:
      $hex_string = { 5da8895da4895da07405e8c57bfdff83c644391e750b5668ac954000e8177bfdff8b3e8d4da451578b07ff50243bc3dbe27d11bb9c9540006a24535750e8f07a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
