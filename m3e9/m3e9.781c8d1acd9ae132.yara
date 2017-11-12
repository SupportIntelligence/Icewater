
rule m3e9_781c8d1acd9ae132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.781c8d1acd9ae132"
     cluster="m3e9.781c8d1acd9ae132"
     cluster_size="206"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus chinky"
     md5_hashes="['02c6dcb9a14f73ca48c282096d8155f1','0a94f2fb70dc082b1743aea448a50f5a','365b5bddc1bafacbc7131ce6338350e6']"

   strings:
      $hex_string = { 00b0999900bb9f9b00a0a19d00a3a49e008894a0008896a5008498a5008d98a200a29ba40088a2ae0085a9ba0092a4b30093a9b7009ba8b9009db3bc00a2a2a2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
