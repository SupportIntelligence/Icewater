
rule k3e9_6334bcc5dd2bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6334bcc5dd2bd932"
     cluster="k3e9.6334bcc5dd2bd932"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['031d801e783ffc8b0b92eda0dd38002f','12c5769f2ff81e2285b325f77d578634','5bcad0ee952d4e09a1a8ea27974728d9']"

   strings:
      $hex_string = { d9c1e902756c8807474b75fa5b5e8b4424085fc3891783c7044974afbafffefe7e8b0603d083f0ff33c28b1683c604a90001018174de84d2742c84f6741ef7c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
