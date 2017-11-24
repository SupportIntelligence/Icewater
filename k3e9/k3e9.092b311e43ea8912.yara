
rule k3e9_092b311e43ea8912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e43ea8912"
     cluster="k3e9.092b311e43ea8912"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag adload"
     md5_hashes="['195ee40ddb590fdcc76902fe54e93382','1a2dbd398405da5d52f7c78a3542b821','fefe2e97f5b0e384c7267fab6000e655']"

   strings:
      $hex_string = { e132e356e555e74ce95feb4fed62ef3ef153f361f55bf7f8f9fafb49fd67ff63017403730579077709700b800dbc0f301169137d1584177c19891b931d911fce }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
