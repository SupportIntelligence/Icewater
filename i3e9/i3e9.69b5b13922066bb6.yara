
rule i3e9_69b5b13922066bb6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.69b5b13922066bb6"
     cluster="i3e9.69b5b13922066bb6"
     cluster_size="511"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector olwrei malicious"
     md5_hashes="['016ba528208c27ab66aa499d01db4602','01fd98becd2946428dedfb596c05343a','1046c8f7b1c384ee34e1c154a0ee403f']"

   strings:
      $hex_string = { 590e0302f3a4088a0688074746e2f804acaae2fc080302ffe40254c3048bc4ffe0c745302a2e657866c7453465008d455c508d5d3053ff95b00100004085c00f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
