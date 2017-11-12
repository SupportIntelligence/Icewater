
rule m3e9_16db1598de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db1598de8bdb16"
     cluster="m3e9.16db1598de8bdb16"
     cluster_size="510"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cerber ransom zbot"
     md5_hashes="['0000bc2fb4090e96f8f45e668899fffc','00a224cd736af899fd3e0d536676e94f','114867e5994d8ef64edbd44253f8f110']"

   strings:
      $hex_string = { aea2293f032f1e45ae929971bbfd2b3faea2294553b9ffc8c1929971c0870070ae62f8c74dba80d03f615970ae87e06fae51d58d4d54e3d088f6de6fae000000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
