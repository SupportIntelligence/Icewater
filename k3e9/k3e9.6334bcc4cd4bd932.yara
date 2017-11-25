
rule k3e9_6334bcc4cd4bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6334bcc4cd4bd932"
     cluster="k3e9.6334bcc4cd4bd932"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['02a9995d9d270969fc0a6e2179735a5f','088fdff0464a912c1019340aa52add65','7764445bd200bd426f7be5942bbf180a']"

   strings:
      $hex_string = { d9c1e902756c8807474b75fa5b5e8b4424085fc3891783c7044974afbafffefe7e8b0603d083f0ff33c28b1683c604a90001018174de84d2742c84f6741ef7c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
