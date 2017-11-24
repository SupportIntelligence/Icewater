
rule m2321_2b324d2ad87bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b324d2ad87bd912"
     cluster="m2321.2b324d2ad87bd912"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod jaike trojandropper"
     md5_hashes="['03bf71ee2c7518e5a0cbb94b7c542066','1a0294cbf3326ddbe3c807a236425b06','c98902f5c0e726daf73049b67e423802']"

   strings:
      $hex_string = { 6a3b520c74f3bc9b675dc0838b9297b748887b69fe65135e6c090b8ce027c60570bdbaf8fa60449046dc991fa5f67d5c38b55d2d37eed06b93357ff2f04ede79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
