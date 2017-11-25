
rule k2321_239249a8da9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.239249a8da9b1912"
     cluster="k2321.239249a8da9b1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi swisyn abzf"
     md5_hashes="['26efccd883003894d38dc3ba8fd562f7','34bea391d90c4bdc719205c0f749ad9d','c6f8a16bcf8385622f75696072627d6e']"

   strings:
      $hex_string = { 708e0d02c69697e74bf8e449ae28e0bfb9b3ac8231b4305de8bbe63966d69f3b3fca537cf7adc2ce2c6c7dd2d7c59aa4ba184213565e1737516c158d438aef83 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
