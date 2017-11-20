
rule m2321_03903b19d34f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.03903b19d34f4912"
     cluster="m2321.03903b19d34f4912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader axzd"
     md5_hashes="['4506d152d11e00a428aaf3c93f1fc333','a62723a0401ce0ca40d7bfd0efb00bae','faaea93a92e348ec8a4e947951737c5e']"

   strings:
      $hex_string = { f647305072314059422b092229e60db9c81b640ef4a28a9c5188ffbc809b3db02e14658f234bd810cb5c4f91759801442496ead1f0e72fd26b6007b85a620bd3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
