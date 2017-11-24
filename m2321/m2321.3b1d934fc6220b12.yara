
rule m2321_3b1d934fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b1d934fc6220b12"
     cluster="m2321.3b1d934fc6220b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['3368b13d8f10c8b9c1a75f3e1f374a8f','3d7b24bb7b27dfedc7d54749edeac323','c3ae5f2c67897d67de0dac5da0dd813b']"

   strings:
      $hex_string = { 949ac0714c477e405cece7a80dad5f2792f33c4207e3761298558db38b6c956df78a4a578cce718ee754f5d7aaf289d464a0f436fa84ee7c6bb2e472900a5e9f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
