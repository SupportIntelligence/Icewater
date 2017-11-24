
rule m2321_6b14d2bccf8bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.6b14d2bccf8bd912"
     cluster="m2321.6b14d2bccf8bd912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['29ea060e82fefe89b793b25c63f28b75','75480470a1ffa5bddd9894dc39639b26','9e3d7c96032de8789aaec0cbe4393fc7']"

   strings:
      $hex_string = { 582ff43176461abfcd376075a1a7650e020d34772368300b1ec2b8ae81b5b2f1516ce618cb1c24ceda40e3ba5e4cd9b8af56790554938d9b0704b46d43b19544 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
