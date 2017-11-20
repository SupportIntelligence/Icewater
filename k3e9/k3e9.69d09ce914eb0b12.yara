
rule k3e9_69d09ce914eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce914eb0b12"
     cluster="k3e9.69d09ce914eb0b12"
     cluster_size="457"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark riskware"
     md5_hashes="['007fd6d1702527d2b126f7d4203f8e13','00b9a720a51406e0e8c18c40bb1d6abc','093294a76ba0a05fcc4350b4a68e57d5']"

   strings:
      $hex_string = { e288fdae3cc494e4f2241d6e3827e145663373f179502e4fc1895132bafc464d4a613d7f87f05bf9fad9c5f676a3736553a98edc1e266741b8928df704d43b2d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
