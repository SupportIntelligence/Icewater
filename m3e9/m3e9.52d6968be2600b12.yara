
rule m3e9_52d6968be2600b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.52d6968be2600b12"
     cluster="m3e9.52d6968be2600b12"
     cluster_size="107"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="conjar vobfus wbna"
     md5_hashes="['14537f1992155b929ae3e8a549bdbec5','1ac9ca88173130487a79ea28cf2f2c25','a3d2a9db22f944e43849ecd22ec1626c']"

   strings:
      $hex_string = { 684ee74100eb338b55f083e20485d274098d4dc0ff15f41140008d45b8508d4dbc516a02ff158411400083c40c8d55b4526a00ff1570104000c38d45c889856c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
