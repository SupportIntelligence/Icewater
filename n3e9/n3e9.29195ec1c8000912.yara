
rule n3e9_29195ec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29195ec1c8000912"
     cluster="n3e9.29195ec1c8000912"
     cluster_size="2678"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy kryptik zaccess"
     md5_hashes="['000285649e47799f70817a725e40723b','0039a4c9237ab04e8e6fab943b0d9104','036f4048ecdc5e5dc6b7a20debcea27d']"

   strings:
      $hex_string = { c78989ffb89289ff573d34fd9d817efeb59796ffba9999ffb39190fe98716efb78514cf5523229e73f2217cf45281da84b2b225e4e2f24275533220cbf9e9bd8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
