
rule k3e9_6b64d36f9d6b5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f9d6b5912"
     cluster="k3e9.6b64d36f9d6b5912"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob patched"
     md5_hashes="['018edb9aabe5426e9ae3cde72d3684c4','1e3c5f1ab21c8b7371eda2d0eccb557f','ae71a8027735adcfa05dd32cf8df3e37']"

   strings:
      $hex_string = { c78989ffb89289ff573d34fd9d817efeb59796ffba9999ffb39190fe98716efb78514cf5523229e73f2217cf45281da84b2b225e4e2f24275533220cbf9e9bd8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
