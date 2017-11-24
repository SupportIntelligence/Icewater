
rule m2321_3331d65b9abb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3331d65b9abb0912"
     cluster="m2321.3331d65b9abb0912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic zbot"
     md5_hashes="['01e7f5219f327855246681e76cae74d6','036181a1e416d7ad6403abc09857e8c1','ab13d9ff2f894df0f8b8fa54d2befe1b']"

   strings:
      $hex_string = { c948dbeb7329be7db01ecdd72fe44ad91f318a6cf1029afdba1b427bfef66e9926f8e08ff0ec3bdc263e2494e6b44ca610f24bd0e8f312ca5ad15838ace5ea4f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
