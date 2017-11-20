
rule k3f9_319d244d98bf0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.319d244d98bf0912"
     cluster="k3f9.319d244d98bf0912"
     cluster_size="4"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack selfdel generickdz"
     md5_hashes="['2af917f24d5381db58e4743a7266ddc9','b8e865856796f6da9a3cec9680fe7802','c39a605576790be46fc97ec6a8c6ed32']"

   strings:
      $hex_string = { 06092fb4c2114a0486ab5d10ce209a0fda230090f0ebdf2be4d1019164c777d55bc10b416064d70f6189c9be4fd8493142361adc3332212744cb157aea7e951d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
