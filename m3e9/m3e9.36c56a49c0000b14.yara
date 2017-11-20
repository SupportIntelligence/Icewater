
rule m3e9_36c56a49c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.36c56a49c0000b14"
     cluster="m3e9.36c56a49c0000b14"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['a7007d998e14f56f2a357afd08ca5158','d70cbdaf9cd9ded37145347680cba74b','eb92c887cb504b68d6d2ba6deff2e031']"

   strings:
      $hex_string = { 4fea627bafaa19c82b37252dbe65a1128a250f63a3f7541cf921c9d615f352ac6e433207fd8217f8e5676c0d51f6bdf152c7bde7c430fc203109881d95291a4d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
