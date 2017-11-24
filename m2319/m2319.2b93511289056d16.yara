
rule m2319_2b93511289056d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b93511289056d16"
     cluster="m2319.2b93511289056d16"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['1392a2a0e340bc435adfac73692688c9','55aee1d4292bfee6b98f1c551ddba523','eaafbd640e56f01248153df1064b9a95']"

   strings:
      $hex_string = { 273a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
