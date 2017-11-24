
rule m2321_2931948fc6210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2931948fc6210912"
     cluster="m2321.2931948fc6210912"
     cluster_size="24"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool kmsauto hackkms"
     md5_hashes="['013bf7788540853237b5e4fd4fc05fdb','253238d2a0c63e55081cb8590a037aa0','8347b54428e983409f05675b3fc5e36e']"

   strings:
      $hex_string = { 004a662a05a8d94fe1ae27f9ff4ea5fb3a74f43895afaf2382419a29e4ac0bf2089f65877e76fc56ebecc4ede6a9f175fa94aa599c70ce3771b65db8207f473b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
