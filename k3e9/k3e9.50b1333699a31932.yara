
rule k3e9_50b1333699a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b1333699a31932"
     cluster="k3e9.50b1333699a31932"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['041656175ae069c571307da9ba410e61','0ab6b5f5409233bc8dac72e8b7ce0be6','bfd04777f5e652c70172d01729030fbb']"

   strings:
      $hex_string = { 000178130001641300014c130001341300011c13000104130001ec120001cc120001b41200018c12000170120001501200012812000108120001bf44ffff40bb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
