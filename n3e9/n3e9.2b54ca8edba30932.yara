
rule n3e9_2b54ca8edba30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b54ca8edba30932"
     cluster="n3e9.2b54ca8edba30932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi dealply malicious"
     md5_hashes="['0fe27e6c939e5da2ab79cbf0e642aad2','58f52515b3e042e184826c7c5060e53d','f60ead4ef1b477094a3a4ec5203393d6']"

   strings:
      $hex_string = { 00fafad200f85f4200808000001c604200228b220030604200adff2f004c6042007fff00006860420090ee9000806042007fffd400986042002e8b5700b06042 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
