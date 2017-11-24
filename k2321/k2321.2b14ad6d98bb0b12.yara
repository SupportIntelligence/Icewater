
rule k2321_2b14ad6d98bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ad6d98bb0b12"
     cluster="k2321.2b14ad6d98bb0b12"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['0c9b44760a8acbf9326f8ba2d76d3564','1dbdb044fae7b6145c1aa59983b89558','da72ed326bb2a92840e46f81ca42e9a5']"

   strings:
      $hex_string = { 4dc8b43b44dfec09f602eb8485e85b3255fa6592f60572b389368b0e605df86881018869ae1aa36fb67f62db6cd57cab401f9c4e76cecd24ec979b4174b5e4ca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
