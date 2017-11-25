
rule m3f7_6b1d909dc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b1d909dc6200b12"
     cluster="m3f7.6b1d909dc6200b12"
     cluster_size="102"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0228f43905f5d5e4e09ab5b31b542c98','034a3f3588412b8e714ea0530d67fa12','1e4ecc430cd8256df8914f2c2711f83d']"

   strings:
      $hex_string = { 38353930323831364334343346464141394438314637323334394445364331393735393246364342373141354135383036424430453135343233453637363230 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
