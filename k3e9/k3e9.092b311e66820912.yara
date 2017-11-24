
rule k3e9_092b311e66820912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e66820912"
     cluster="k3e9.092b311e66820912"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag clfcen"
     md5_hashes="['19b473b47c99765d494eea08e1983665','6885c948aa581bd33039104e4564c591','f819125827f929d45a59afd4986605ca']"

   strings:
      $hex_string = { e132e356e555e74ce95feb4fed62ef3ef153f361f55bf7f8f9fafb49fd67ff63017403730579077709700b800dbc0f301169137d1584177c19891b931d911fce }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
