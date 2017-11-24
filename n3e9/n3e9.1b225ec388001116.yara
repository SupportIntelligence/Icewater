
rule n3e9_1b225ec388001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b225ec388001116"
     cluster="n3e9.1b225ec388001116"
     cluster_size="210"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel autorun"
     md5_hashes="['019b17f82808e540be9962e2f95bae3c','098df916ec42917e0edc03562f27ab36','42bbadef9a46d40686d6777f03d975cd']"

   strings:
      $hex_string = { a27a2e0b5034ae33f2ecc16ce686f96d710ec3000cf429b759780cac76d9a687a5c0856b382294bfd6e04ddac202577027ea452f5a48f8f690935f1131afc8ab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
